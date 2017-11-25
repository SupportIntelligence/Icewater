
rule m3e9_611c99c1c6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c99c1c6620b12"
     cluster="m3e9.611c99c1c6620b12"
     cluster_size="85"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="diple vobfus changeup"
     md5_hashes="['0cb903320f044fd5ebbe7fe509beb1ea','0d9d2346c382e842e9365197e9a260be','7778aedf9253b2e4468ecf9fc93eaf30']"

   strings:
      $hex_string = { 4fdffeff8d45b0508d45c0506a02e88edffeff83c40cc3c38d75d08b7d08a5a5a5a58b45088b4de064890d000000005f5e5bc9c20c00558bec83ec1868e62e40 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
