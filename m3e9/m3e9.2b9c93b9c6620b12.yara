
rule m3e9_2b9c93b9c6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b9c93b9c6620b12"
     cluster="m3e9.2b9c93b9c6620b12"
     cluster_size="76"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma susp"
     md5_hashes="['026d9f2a29934864fcd5d15def1130ec','05c470a2bbbab79430f125a4e1dffcf9','33b94815aa4c59f4f4b285b310be1702']"

   strings:
      $hex_string = { c13246cb2ec28d7b3558b11345258f6741ee294e0fae39c40c9dfc0003f8b5c5f63bfb0bcf2f2337df7d307804d1606975cd973651707a196c423caf8c8eadbe }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
