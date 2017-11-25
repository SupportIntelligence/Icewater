
rule m3e9_5da24c6251145aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5da24c6251145aba"
     cluster="m3e9.5da24c6251145aba"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys autorun"
     md5_hashes="['4951dd7581fc763ad1410a6dbeb9df6b','49591da3b5d313b34cef6f83209132f3','b9b6d8e1fc4eb7d54c3c6efcfc556902']"

   strings:
      $hex_string = { 8a54007174fe6c74fef501000000c71cbc02f4ff707aff6cc8fe8524006cccfe8518006be4fee7f500010000c4fd6914ff25480c002c03000000fce038fffd67 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
