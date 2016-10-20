package com.beecode.nectar.sangforvpn;

/**
 * Created by airyuxun on 2016/10/18.
 */

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;
import android.widget.Toast;

import com.sangfor.ssl.IVpnDelegate;
import com.sangfor.ssl.SFException;
import com.sangfor.ssl.SangforAuth;
import com.sangfor.ssl.common.VpnCommon;
import com.sangfor.ssl.service.setting.SystemConfiguration;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static android.content.ContentValues.TAG;
public class SangforEngine implements  IVpnDelegate,VPNEventListener{
    private Activity activity;
    private InetAddress m_iAddr;
    public int VPN_PORT = 443;
    public boolean showToast;
    private VPNEventListener eventListener = this;
    String mIP;
    public SangforAuth requireInstance(){
        return SangforAuth.getInstance();
    }
    public void newInstance(Activity activity,VPNEventListener eventListener){
        this.activity = activity;
        initVPN(this.activity);
        this.eventListener = eventListener;
    }
    public void init(String ip){
        this.mIP = ip;
        initSslVpn(ip);
    }
    public void loginWithCert(String name,String pass){
        doVpnLogin(IVpnDelegate.AUTH_TYPE_CERTIFICATE,name,pass,null);
    }
    public void loginWithUser(String name,String pass){
        doVpnLogin(IVpnDelegate.AUTH_TYPE_PASSWORD,name,pass,null);
    }
    public void loginWithSMSCode(String code){
        doVpnLogin(IVpnDelegate.AUTH_TYPE_PASSWORD,null,null,code);
    }
    public void loginWithSMS1(){
        doVpnLogin(IVpnDelegate.AUTH_TYPE_SMS1,null,null,null);
    }
    /**
     * 处理认证，通过传入认证类型（需要的话可以改变该接口传入一个hashmap的参数用户传入认证参数）.
     * 也可以一次性把认证参数设入，这样就如果认证参数全满足的话就可以一次性认证通过，可见下面屏蔽代码
     *
     * @param authType
     *            认证类型
     * @param name 名称
     *
     * @param code 验证码
     * @param pass 密码
     * @throws SFException
     */
    public void doVpnLogin(int authType,String name,String pass,String code) {
        Log.d(TAG, "doVpnLogin authType " + authType);

        boolean ret = false;
        SangforAuth sfAuth = SangforAuth.getInstance();

        switch (authType) {
            case IVpnDelegate.AUTH_TYPE_CERTIFICATE:

                sfAuth.setLoginParam(IVpnDelegate.CERT_PASSWORD, pass);
                sfAuth.setLoginParam(IVpnDelegate.CERT_P12_FILE_NAME, name);
                ret = sfAuth.vpnLogin(IVpnDelegate.AUTH_TYPE_CERTIFICATE);
                break;
            case IVpnDelegate.AUTH_TYPE_PASSWORD:
                String user = name;
                String passwd = pass;
                String rndcode = code;
                sfAuth.setLoginParam(IVpnDelegate.PASSWORD_AUTH_USERNAME, user);
                sfAuth.setLoginParam(IVpnDelegate.PASSWORD_AUTH_PASSWORD, passwd);
//                sfAuth.setLoginParam(IVpnDelegate.SET_RND_CODE_STR, rndcode);
                ret = sfAuth.vpnLogin(IVpnDelegate.AUTH_TYPE_PASSWORD);
                break;
            case IVpnDelegate.AUTH_TYPE_SMS:
                String smsCode = code;
                sfAuth.setLoginParam(IVpnDelegate.SMS_AUTH_CODE, smsCode);
                ret = sfAuth.vpnLogin(IVpnDelegate.AUTH_TYPE_SMS);
                break;
            case IVpnDelegate.AUTH_TYPE_SMS1:
                ret = sfAuth.vpnLogin(IVpnDelegate.AUTH_TYPE_SMS1);
                break;
            default:
                Log.w(TAG, "default authType " + authType);
                break;
        }

        if (ret == true) {
            Log.i(TAG, "success to call login method");
        } else {
            Log.i(TAG, "fail to call login method");
        }

    }
    private void initVPN(Activity activity){
        SangforAuth sfAuth = SangforAuth.getInstance();
        try {
            sfAuth.init(activity, this, SangforAuth.AUTH_MODULE_EASYAPP);
//            sfAuth.init(activity, this, SangforAuth.AUTH_MODULE_L3VPN);
            sfAuth.setLoginParam(AUTH_CONNECT_TIME_OUT, String.valueOf(5));
        } catch (SFException e) {
            e.printStackTrace();
        }
    }
    public void start(){
        SangforAuth sfAuth = SangforAuth.getInstance();
        sfAuth.vpnL3vpnStart();
    }
    private boolean initSslVpn(String withIP) {
        SangforAuth sfAuth = SangforAuth.getInstance();

        m_iAddr = null;
        final String ip = withIP;

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    m_iAddr = InetAddress.getByName(ip);
                    Log.i(TAG, "ip Addr is : " + m_iAddr.getHostAddress());
                } catch (UnknownHostException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        });
        t.start();
        try {
            t.join();
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (m_iAddr == null || m_iAddr.getHostAddress() == null) {
            Log.d(TAG, "vpn host error");
            return false;
        }
        long host = VpnCommon.ipToLong(m_iAddr.getHostAddress());
        int port = VPN_PORT;

        if (sfAuth.vpnInit(host, port) == false) {
            Log.d(TAG, "vpn init fail, errno is " + sfAuth.vpnGeterr());
            return false;
        }

        return true;
    }



    @Override
    public void vpnCallback(int vpnResult, int authType) {
        SangforAuth sfAuth = SangforAuth.getInstance();
        eventListener.onVPNCallback(vpnResult,authType);
        switch (vpnResult) {
            case IVpnDelegate.RESULT_VPN_INIT_FAIL:
                /**
                 * 初始化vpn失败
                 */
                Log.i(TAG, "RESULT_VPN_INIT_FAIL, error is " + sfAuth.vpnGeterr());
                displayToast("RESULT_VPN_INIT_FAIL, error is " + sfAuth.vpnGeterr());
                eventListener.onVPNInitSuccess(authType);
                break;

            case IVpnDelegate.RESULT_VPN_INIT_SUCCESS:
                /**
                 * 初始化vpn成功，接下来就需要开始认证工作了
                 */
                Log.i(TAG,
                        "RESULT_VPN_INIT_SUCCESS, current vpn status is " + sfAuth.vpnQueryStatus());
                displayToast("RESULT_VPN_INIT_SUCCESS, current vpn status is "
                        + sfAuth.vpnQueryStatus());
                Log.i(TAG, "vpnResult===================" + vpnResult  + "\nauthType ==================" + authType);
                // 初始化成功，进行认证操作
                eventListener.onVPNInitSuccess(authType);
                break;

            case IVpnDelegate.RESULT_VPN_AUTH_FAIL:
                /**
                 * 认证失败，有可能是传入参数有误，具体信息可通过sfAuth.vpnGeterr()获取
                 */
                String errString = sfAuth.vpnGeterr();
                Log.i(TAG, "RESULT_VPN_AUTH_FAIL, error is " + sfAuth.vpnGeterr());
                displayToast("RESULT_VPN_AUTH_FAIL, error is " + sfAuth.vpnGeterr());
                eventListener.onVPNAuthFail(authType);
                break;

            case IVpnDelegate.RESULT_VPN_AUTH_SUCCESS:
                /**
                 * 认证成功，认证成功有两种情况，一种是认证通过，可以使用sslvpn功能了，另一种是前一个认证（如：用户名密码认证）通过，
                 * 但需要继续认证（如：需要继续证书认证）
                 */
                if (authType == IVpnDelegate.AUTH_TYPE_NONE) {
                    Log.i(TAG, "welcom to sangfor sslvpn!");
                    displayToast("welcom to sangfor sslvpn!");

                    // 若为L3vpn流程，认证成功后开启自动开启l3vpn服务
                    if (SangforAuth.getInstance().getModuleUsed() == SangforAuth.AUTH_MODULE_EASYAPP) {
                        // EasyApp流程，认证流程结束，可访问资源。

                    }
                    eventListener.onVPNAuthSuccess(authType);
                } else {
                    Log.i(TAG, "auth success, and need next auth, next auth type is " + authType);
                    displayToast("auth success, and need next auth, next auth type is " + authType);

                    if (authType == IVpnDelegate.AUTH_TYPE_SMS) {
                        // 输入短信验证码
                        displayToast("you need send sms code.");
                        eventListener.onVPNAuthStepSuccess(authType);
                    } else {
                        eventListener.onVPNAuthSuccess(authType);
                    }
                }
                break;
            case IVpnDelegate.RESULT_VPN_AUTH_CANCEL:
                Log.i(TAG, "RESULT_VPN_AUTH_CANCEL");
                displayToast("RESULT_VPN_AUTH_CANCEL");
                break;
            case IVpnDelegate.RESULT_VPN_AUTH_LOGOUT:
                /**
                 * 主动注销（自己主动调用logout接口）或者被动注销（通过控制台把用户踢掉）均会调用该接口
                 */
                Log.i(TAG, "RESULT_VPN_AUTH_LOGOUT");
                displayToast("RESULT_VPN_AUTH_LOGOUT");
                break;
            case IVpnDelegate.RESULT_VPN_L3VPN_FAIL:
                /**
                 * L3vpn启动失败，有可能是没有l3vpn资源，具体信息可通过sfAuth.vpnGeterr()获取
                 */
                Log.i(TAG, "RESULT_VPN_L3VPN_FAIL, error is " + sfAuth.vpnGeterr());
                displayToast("RESULT_VPN_L3VPN_FAIL, error is " + sfAuth.vpnGeterr());
                break;
            case IVpnDelegate.RESULT_VPN_L3VPN_SUCCESS:
                /**
                 * L3vpn启动成功
                 */
                registerNetWorkBroadcasts(); //注册网络监听广播
                Log.i(TAG, "RESULT_VPN_L3VPN_SUCCESS ===== " + SystemConfiguration.getInstance().getSessionId() );
                displayToast("RESULT_VPN_L3VPN_SUCCESS");
                // L3vpn流程，认证流程结束，可访问资源。
                eventListener.onVPNAuthSuccess(authType);
                break;
            case IVpnDelegate.VPN_STATUS_ONLINE:
                /**
                 * 与设备连接建立
                 */
                Log.i(TAG, "online");
                displayToast("online");
                break;
            case IVpnDelegate.VPN_STATUS_OFFLINE:
                /**
                 * 与设备连接断开
                 */
                Log.i(TAG, "offline");
                displayToast("offline");
                break;
            default:
                /**
                 * 其它情况，不会发生，如果到该分支说明代码逻辑有误
                 */
                Log.i(TAG, "default result, vpn result is " + vpnResult);
                displayToast("default result, vpn result is " + vpnResult);

                break;
        }

    }
    public void vpnRndCodeCallback(byte[] data){
        eventListener.onVPNRndCodeCallback(data);
    }
    @Override
    public void onVPNRndCodeCallback(byte[] data) {
//        Log.d(TAG, "vpnRndCodeCallback data: " + Boolean.toString(data==null));
//        if (data != null) {
//            Drawable drawable = Drawable.createFromStream(new ByteArrayInputStream(data),
//                    "rand_code");
//            imgbtn_rnd_code.setBackgroundDrawable(drawable);
//        }
    }

    @Override
    public void onReloginfaild() {

    }

    @Override
    public void onReloginSuccess() {

    }

    @Override
    public void onStratRelogin() {

    }

    @Override
    public void reloginCallback(int status, int result) {
        switch (status){

            case IVpnDelegate.VPN_START_RELOGIN:
                Log.e(TAG, "relogin callback start relogin start ...");
                eventListener.onStratRelogin();
                break;
            case IVpnDelegate.VPN_END_RELOGIN:
                Log.e(TAG, "relogin callback end relogin ...");
                if (result == IVpnDelegate.VPN_RELOGIN_SUCCESS){
                    Log.e(TAG, "relogin callback, relogin success!");
                    eventListener.onReloginSuccess();
                } else {
                    Log.e(TAG, "relogin callback, relogin failed");
                    eventListener.onReloginfaild();
                }
                break;
        }

    }
    private void displayToast(String str) {
        Toast.makeText(activity, str, Toast.LENGTH_LONG).show();
    }


    @Override
    public void onVPNInitSuccess(int authType) {

//            initSslVpn(mIP);//登录
    }

    @Override
    public void onVPNAuthSuccess(int authType) {

    }

    @Override
    public void onVPNAuthStepSuccess(int authType) {

    }

    @Override
    public void onVPNAuthFail(int auth) {

    }

    @Override
    public void onVPNCallback(int vpnResult, int authType) {

    }

    public NetWorkBroadcastReceiver mNetWorkReceiver = null;
    /**
     * 注册网络状态变化广播接收器
     */
    private void registerNetWorkBroadcasts() {
        Log.d(TAG, "registerNetWorkBroadcasts.");

        // 注册网络广播接收器
        if (mNetWorkReceiver == null) {
            // 创建IntentFilter对象
            IntentFilter networkFilter = new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION);
            // 注册Broadcast Receiver
            mNetWorkReceiver = new NetWorkBroadcastReceiver();
            activity.registerReceiver(mNetWorkReceiver, networkFilter);
        }
    }


    /**
     * 取消注册网络状态变化广播接收器
     */
    private void unRegisterNetWorkBroadcasts() {
        Log.d(TAG, "unRegisterBroadcasts.");

        // 取消注册Broadcast Receiver
        if (mNetWorkReceiver != null) {
            activity.unregisterReceiver(mNetWorkReceiver);
            mNetWorkReceiver = null;
        }
    }


    /** 接收网络状态广播消息 **/
    private class NetWorkBroadcastReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            ConnectivityManager connManager = (ConnectivityManager) context
                    .getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo mobNetInfo = connManager.getNetworkInfo(ConnectivityManager.TYPE_MOBILE);

            NetworkInfo wifiInfo = connManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
            if ((mobNetInfo == null || !mobNetInfo.isConnected()) && (wifiInfo == null || !wifiInfo.isConnected())) {
                // 网络断开
                eventListener.onEthStateChanged(false);   //再此函数里面做判断，如果网络断开做注销操作
                Log.d(TAG, "Network is disconnected.");
            } else if ((mobNetInfo != null && mobNetInfo.isConnected()) || (wifiInfo != null && wifiInfo.isConnected())) {
                // 网络恢复
                eventListener.onEthStateChanged(true);  //判断正常的话，重新登陆
                Log.d(TAG, "Network is connected.");
            }
        }
    }


    /**
     * 当网络发生变化时通告函数，这个地方无需处理离线情况，因为离线情况下不会注册监听网络的广播接收器
     */
    public void onEthStateChanged(boolean connected) {
//        if (connected) {
//            initSslVpn(mIP);//登录
//        } else {
//            SangforAuth.getInstance().vpnLogout(); //注销
//
//        }
    }
}
