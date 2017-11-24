
rule m2319_231b6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.231b6a49c0000b12"
     cluster="m2319.231b6a49c0000b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html redirector"
     md5_hashes="['0019c91ac883aa934b7827c4c43bb00c','2f2863864c67c3070d4570b8289874a4','f52eaa9e2d9889060ff566a7fc5e0266']"

   strings:
      $hex_string = { 3b3928322e3328372b342b6b2b62292c36293b3928322e3328342b61292c36293b272c32362c32362c277c7661727c646f63756d656e747c77726974657c6b30 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
