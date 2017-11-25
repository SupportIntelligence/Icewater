
rule m3ed_104ee5a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.104ee5a1c2000b32"
     cluster="m3ed.104ee5a1c2000b32"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="download malicious patched"
     md5_hashes="['317af1b885795f3dae031275fb746743','41f5f44f8d28b17545089f86967b6676','db4b9b49c440a172d84db4dbd3823a38']"

   strings:
      $hex_string = { 0016301d30a030a830bd30c8305b31423251326c329135d4365b388b38b138993ac73ccb3ccf3cd33cd73cdb3cdf3ce33cf03c023dd43dde3deb3d063e0d3e25 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
