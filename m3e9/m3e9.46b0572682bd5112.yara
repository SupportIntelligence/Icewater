
rule m3e9_46b0572682bd5112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.46b0572682bd5112"
     cluster="m3e9.46b0572682bd5112"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik vbobfus"
     md5_hashes="['b05df80abdff94debe538eab53a418e5','b3bf430f8f56b654d2b2d336f8ac9640','e826881edf58a19ef4a3948009ad70d8']"

   strings:
      $hex_string = { 66676e5f6e59556f987a726f6d7990a2dcf9fffdfff7f7b7000000f8ffff0312282c20101111101a585765736c30667a635f5c75b3a79cc0cecdaea9aae6f2fa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
