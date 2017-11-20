
rule m3e9_0b1c93b9c6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b1c93b9c6620b12"
     cluster="m3e9.0b1c93b9c6620b12"
     cluster_size="25"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma susp"
     md5_hashes="['2124f0f8494c76deb9d25e18003e958f','285a0d866c5e69c576c4188c66b7a52c','9babbad97a7c4c06c149d4e67cb4c208']"

   strings:
      $hex_string = { c13246cb2ec28d7b3558b11345258f6741ee294e0fae39c40c9dfc0003f8b5c5f63bfb0bcf2f2337df7d307804d1606975cd973651707a196c423caf8c8eadbe }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
