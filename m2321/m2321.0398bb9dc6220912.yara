
rule m2321_0398bb9dc6220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0398bb9dc6220912"
     cluster="m2321.0398bb9dc6220912"
     cluster_size="33"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader axzd"
     md5_hashes="['04f1a1682e4700870da967cf8630c34c','05cf78cb09437db7b741cf9fe81d2e93','902448b53bd48c241546bd453b67b7fb']"

   strings:
      $hex_string = { 8342be164411cbbf8e2f478cb1fa78c8f2bb356e1f393ee677d48f3a23845dfe4668ee120d64dc3785b8c993a90f1d229ca743cdbdcade2af4e3ed1dba98f315 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
