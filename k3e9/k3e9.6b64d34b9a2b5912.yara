
rule k3e9_6b64d34b9a2b5912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b9a2b5912"
     cluster="k3e9.6b64d34b9a2b5912"
     cluster_size="170"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob patched"
     md5_hashes="['01c72bb873605b20eaae7fe79dc2ede9','03fc9cfb63cdfc742a0e6ec7d11c6bd1','4c29b1bd69df4273fa76db296b683582']"

   strings:
      $hex_string = { c78989ffb89289ff573d34fd9d817efeb59796ffba9999ffb39190fe98716efb78514cf5523229e73f2217cf45281da84b2b225e4e2f24275533220cbf9e9bd8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
