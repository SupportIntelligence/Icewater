
rule m2319_2b9b3199c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9b3199c2200b12"
     cluster="m2319.2b9b3199c2200b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script clicker"
     md5_hashes="['6d3611df0b16f679a920298772e075bb','7cc8b4c5d19ca64ad2be7fd6fe1ef318','cbf41bfdfe160891555d693dcd5a7364']"

   strings:
      $hex_string = { 46756c6c2729293b0a5f5769646765744d616e616765722e5f526567697374657257696467657428275f426c6f674172636869766556696577272c206e657720 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
