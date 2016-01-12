package com.bulovic.sshkey;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class OpenSSHPublicKeyFormatDecoderTest {
    public static final String RSA_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOrrZ0oN66Ud2lac26qeJT0g/8W4nla86wtC8jNSWTjbKXwJrl8wN8/6uGm75eXFJCCYEPXhO2zJHubS3sJrF9E0twu75iKP86uJM+ZEnf1mzElSfEMteGfSlZc70DLWtvrLKVQOcmvuh/5MlFSBSJrPDNwYZZIWdOqLcNI7YNeyZuX8wKktmOwaqopdB72qoPF24KtAt0ILhuMq+Y9u7ovqyuZlgUvsYBUxfuJVt2GT3+sLX+in2+ihTsABnfmqW5jdH6aPMMy/LYiJBtq4cf/K+L5MUiZCfbwTSw1mpGePUKB850mR4M0vXnMFkZbSkrWCWTMkzoksP0tEZGxLql user@example";
    public static final String DSA_KEY = "ssh-dss AAAAB3NzaC1kc3MAAACBAKl6Mn4HS41vdcppjBn4PiMe8EEcyVVpYg6iPwX+EQ82ROm0AscfcsHhfrkuz+kthpvrhiwGB9B6XAcm1iIFitUDI+aF0wEsL91kSbRN4rp82n9laBezR8Sau+TR8RKC+dM1Ak44ylveJCyf5PrY89erXGzGVyx00ftx9TYp8gL9AAAAFQDTQiUj+yg941j2qQcaUKQ1+WaGTQAAAIBAYc00ybt3rwyHFiobF6WuQKbDS346I+G3okK7/AzItmYk7bNuBoSsh+OqNvOkSul9JAB5iCz/c9CRB3174Mhu6v8K+5vdWXV15QWZhPCEyythHajWFevii4qtgLSsM0NSRuZTPrYkmF31KnaVlGvAcTpbz8wJ/M0tM12Qins4AAAAAIASnCfscxXZo0QfyvcbkvBVVDcLSQp+BzEtGFfqacwmBBFO58Lqy36m7aUxRmbxmpdVBqbdl4cu+8l1AQoWHPqknK15ykMyNaPsZCiT2dRfjvDxR0rmmu2yf97d+FDtqD3OMIqZfNXKET3NdPyi565KClnFi6NcOI/znUHsYgLAqQ== user@example";
    public static final String RSA_KEY_SHORT = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOrrZ0oN66Ud2lac26qeJT0g/8W4nla86wtC8jNSWTjbKXwJrl8wN8/6uGm75eXFJCCYEPXhO2zJHubS3sJrF9E0twu75iKP86uJM+ZEnf1mzElSfEMteGfSlZc70DLWtvrLKVQOcmvuh/5MlFSBSJrPDNwYZZIWdOqLcNI7YNeyZuX8wKktmOwaqopdB72qoPF24KtAt0ILhuMq+Y9u7ovqyuZlgUvsYBUxfuJVt2GT3+sLX+in2+ihTsABnfmqW5jdH6aPMMy/LYiJBtq4cf/K+L5MUiZCfbwTSw1mpGePUKB850mR4M0vXnMFkZbSkrWCWTMkzoksP0tEZGxLql";
    public static final String DSA_KEY_SHORT = "ssh-dss AAAAB3NzaC1kc3MAAACBAKl6Mn4HS41vdcppjBn4PiMe8EEcyVVpYg6iPwX+EQ82ROm0AscfcsHhfrkuz+kthpvrhiwGB9B6XAcm1iIFitUDI+aF0wEsL91kSbRN4rp82n9laBezR8Sau+TR8RKC+dM1Ak44ylveJCyf5PrY89erXGzGVyx00ftx9TYp8gL9AAAAFQDTQiUj+yg941j2qQcaUKQ1+WaGTQAAAIBAYc00ybt3rwyHFiobF6WuQKbDS346I+G3okK7/AzItmYk7bNuBoSsh+OqNvOkSul9JAB5iCz/c9CRB3174Mhu6v8K+5vdWXV15QWZhPCEyythHajWFevii4qtgLSsM0NSRuZTPrYkmF31KnaVlGvAcTpbz8wJ/M0tM12Qins4AAAAAIASnCfscxXZo0QfyvcbkvBVVDcLSQp+BzEtGFfqacwmBBFO58Lqy36m7aUxRmbxmpdVBqbdl4cu+8l1AQoWHPqknK15ykMyNaPsZCiT2dRfjvDxR0rmmu2yf97d+FDtqD3OMIqZfNXKET3NdPyi565KClnFi6NcOI/znUHsYgLAqQ==";
    public static final String RSA_KEY_SHORT2 = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDOrrZ0oN66Ud2lac26qeJT0g/8W4nla86wtC8jNSWTjbKXwJrl8wN8/6uGm75eXFJCCYEPXhO2zJHubS3sJrF9E0twu75iKP86uJM+ZEnf1mzElSfEMteGfSlZc70DLWtvrLKVQOcmvuh/5MlFSBSJrPDNwYZZIWdOqLcNI7YNeyZuX8wKktmOwaqopdB72qoPF24KtAt0ILhuMq+Y9u7ovqyuZlgUvsYBUxfuJVt2GT3+sLX+in2+ihTsABnfmqW5jdH6aPMMy/LYiJBtq4cf/K+L5MUiZCfbwTSw1mpGePUKB850mR4M0vXnMFkZbSkrWCWTMkzoksP0tEZGxLql";
    public static final String DSA_KEY_SHORT2 = "AAAAB3NzaC1kc3MAAACBAKl6Mn4HS41vdcppjBn4PiMe8EEcyVVpYg6iPwX+EQ82ROm0AscfcsHhfrkuz+kthpvrhiwGB9B6XAcm1iIFitUDI+aF0wEsL91kSbRN4rp82n9laBezR8Sau+TR8RKC+dM1Ak44ylveJCyf5PrY89erXGzGVyx00ftx9TYp8gL9AAAAFQDTQiUj+yg941j2qQcaUKQ1+WaGTQAAAIBAYc00ybt3rwyHFiobF6WuQKbDS346I+G3okK7/AzItmYk7bNuBoSsh+OqNvOkSul9JAB5iCz/c9CRB3174Mhu6v8K+5vdWXV15QWZhPCEyythHajWFevii4qtgLSsM0NSRuZTPrYkmF31KnaVlGvAcTpbz8wJ/M0tM12Qins4AAAAAIASnCfscxXZo0QfyvcbkvBVVDcLSQp+BzEtGFfqacwmBBFO58Lqy36m7aUxRmbxmpdVBqbdl4cu+8l1AQoWHPqknK15ykMyNaPsZCiT2dRfjvDxR0rmmu2yf97d+FDtqD3OMIqZfNXKET3NdPyi565KClnFi6NcOI/znUHsYgLAqQ==";
    public static final String RSA_KEY_SHORT3 = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDOrrZ0oN66Ud2lac26qeJT0g/8W4nla86wtC8jNSWTjbKXwJrl8wN8/6uGm75eXFJCCYEPXhO2zJHubS3sJrF9E0twu75iKP86uJM+ZEnf1mzElSfEMteGfSlZc70DLWtvrLKVQOcmvuh/5MlFSBSJrPDNwYZZIWdOqLcNI7YNeyZuX8wKktmOwaqopdB72qoPF24KtAt0ILhuMq+Y9u7ovqyuZlgUvsYBUxfuJVt2GT3+sLX+in2+ihTsABnfmqW5jdH6aPMMy/LYiJBtq4cf/K+L5MUiZCfbwTSw1mpGePUKB850mR4M0vXnMFkZbSkrWCWTMkzoksP0tEZGxLql user@example";
    public static final String DSA_KEY_SHORT3 = "AAAAB3NzaC1kc3MAAACBAKl6Mn4HS41vdcppjBn4PiMe8EEcyVVpYg6iPwX+EQ82ROm0AscfcsHhfrkuz+kthpvrhiwGB9B6XAcm1iIFitUDI+aF0wEsL91kSbRN4rp82n9laBezR8Sau+TR8RKC+dM1Ak44ylveJCyf5PrY89erXGzGVyx00ftx9TYp8gL9AAAAFQDTQiUj+yg941j2qQcaUKQ1+WaGTQAAAIBAYc00ybt3rwyHFiobF6WuQKbDS346I+G3okK7/AzItmYk7bNuBoSsh+OqNvOkSul9JAB5iCz/c9CRB3174Mhu6v8K+5vdWXV15QWZhPCEyythHajWFevii4qtgLSsM0NSRuZTPrYkmF31KnaVlGvAcTpbz8wJ/M0tM12Qins4AAAAAIASnCfscxXZo0QfyvcbkvBVVDcLSQp+BzEtGFfqacwmBBFO58Lqy36m7aUxRmbxmpdVBqbdl4cu+8l1AQoWHPqknK15ykMyNaPsZCiT2dRfjvDxR0rmmu2yf97d+FDtqD3OMIqZfNXKET3NdPyi565KClnFi6NcOI/znUHsYgLAqQ== user@example";
    public static final String RSA_KEY_BROKEN = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOrrZ0oN66Ud2lac26qeJT0g/8W4nla86wtC8jNSWTjbKXwJrl8wN8/6uGm75eXFJCCYEPXhO2zJHubS3sJrF9E0twu75iKP86uJM+ZEnf1mzElSfEMteGfSlZc70DLWtvrLKVQOcmvuh/5MlFSBSJrPDNwYZZIWdOqLcNI7YNeyZuX8wKktmOwaqopdB72qoPF24KtAt0ILhuMq+Y9u7ovqyuZlgUvsYBUxfuJVt2GT3+LX+in2+ihTsABnfmqW5jdH6aPMMy/LYiJBtq4cf/K+L5MUiZCfbwTSw1mpGePUKB850mR4M0vXnMFkZbSkrWCWTMkzoksP0tEZGxLql user@example";
    public static final String DSA_KEY_BROKEN = "ssh-dss AAAAB3NzaC1kc3MAAACBAKl6Mn4HS41vdcppjBn4PiMe8EEcyVVpYg6iPwX+EQ82ROm0AscfcsHhfrkuz+kthpvrhiwGB9B6XAcm1iIFitUDI+aF0wEsL91kSbRN4rp82n9laBezR8Sau+TR8RKC+dM1Ak44ylveJCyf5PrY89erXGzGVyx00ftx9TYp8gL9AAAAFQDTQiUj+yg941j2qQcaUKQ1+WaGTQAAAIBAYc00ybt3rwyHFiobF6WuQKbDS346I+G3okK7/AzItmYk7bNuBoSsh+OqNvOkSul9JAB5iCz/c9CRB3174Mhu6v8K+5vdWXV15QWZhPCEyythHajWFevii4qtgLSsM0NSRuZTPrYkmF31KnaVlGvAcTpbz8wJ/M0tM12Qins4AAAAAIASnCfscxXZo0QfyvcbkvBVVDcLSQp+BzEtGFfqacwmBBFO58Lqy36m7aUxRmbxmpdVBqbdl4cu+8l1AQoWHPqknK15ykMyNaPsZCiT2dRfjvDxR0rmmu2yf97d+FDtqDOMIqZfNXKET3NdPyi565KClnFi6NcOI/znUHsYgLAqQ== user@example";

    @Test
    public void testRSA1() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(RSA_KEY);
        assertEquals(openSSHPublicKeyFormatDecoder.getType(), OpenSSHPublicKeyFormatDecoder.SSH_RSA);
        assertEquals(openSSHPublicKeyFormatDecoder.getComment(), "user@example");
    }

    @Test
    public void testRSA2() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(RSA_KEY_SHORT);
        assertEquals(openSSHPublicKeyFormatDecoder.getType(), OpenSSHPublicKeyFormatDecoder.SSH_RSA);
        assertNull(openSSHPublicKeyFormatDecoder.getComment());
    }

    @Test(expected=IllegalArgumentException.class)
    public void testRSA3() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(RSA_KEY_SHORT2);

    }

    @Test(expected=IllegalArgumentException.class)
    public void testRSA4() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(RSA_KEY_SHORT3);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testRSA5() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(RSA_KEY_BROKEN);
    }

    @Test
    public void testDSA1() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(DSA_KEY);
        assertEquals(openSSHPublicKeyFormatDecoder.getType(), OpenSSHPublicKeyFormatDecoder.SSH_DSS);
        assertEquals(openSSHPublicKeyFormatDecoder.getComment(), "user@example");
    }

    @Test
    public void testDSA2() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(DSA_KEY_SHORT);
        assertEquals(openSSHPublicKeyFormatDecoder.getType(), OpenSSHPublicKeyFormatDecoder.SSH_DSS);
        assertNull(openSSHPublicKeyFormatDecoder.getComment());
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDSA3() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(DSA_KEY_SHORT2);

    }

    @Test(expected=IllegalArgumentException.class)
    public void testDSA4() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(DSA_KEY_SHORT3);
    }

    @Test(expected=ArrayIndexOutOfBoundsException.class)
    public void testDSA5() throws Exception {
        OpenSSHPublicKeyFormatDecoder openSSHPublicKeyFormatDecoder = new OpenSSHPublicKeyFormatDecoder(DSA_KEY_BROKEN);
    }
}