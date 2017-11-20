
rule k3e9_293b19609cd96996
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.293b19609cd96996"
     cluster="k3e9.293b19609cd96996"
     cluster_size="359"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted click"
     md5_hashes="['001f4bf466174b7ea3fbba9a35eea9cd','02ab7f42a98916ebce37c25c5991f3d6','0e57b53680dfa85104d92189112b0bea']"

   strings:
      $hex_string = { 1674dbbe474898bfde990249202fdf657d9e2a75eaf1b15db71d5b0d6dc273a3383e3637764570f8c4da2df94da1d913cf6b1030fbe954a22860696606ae6277 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
