
rule m3e9_1b9c97bdc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1b9c97bdc6620b12"
     cluster="m3e9.1b9c97bdc6620b12"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma susp"
     md5_hashes="['1566ee394bf1949fa78ca40525fe2482','7f3009e2c38983711f2bd04e8663a021','f38b272de2b19a50dc790c1cb1b2ec08']"

   strings:
      $hex_string = { c13246cb2ec28d7b3558b11345258f6741ee294e0fae39c40c9dfc0003f8b5c5f63bfb0bcf2f2337df7d307804d1606975cd973651707a196c423caf8c8eadbe }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
