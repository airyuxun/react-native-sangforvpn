package com.beecode.nectar.sangforvpn;

/**
 * Created by airyuxun on 2016/10/18.
 */

public interface VPNEventListener {
    public void onVPNInitSuccess(int authType);
    public void onVPNAuthSuccess(int authType);
    public void onVPNAuthStepSuccess(int authType);
    public void onVPNAuthFail(int auth);
    /**
     *
     * @param vpnResult
     * @param authType
     */
    public void onVPNCallback(int vpnResult, int authType);
    public void onEthStateChanged(boolean connected);
    public void onVPNRndCodeCallback(byte[] data);

    public void onReloginfaild();

    public void onReloginSuccess();

    public void onStratRelogin();
}
