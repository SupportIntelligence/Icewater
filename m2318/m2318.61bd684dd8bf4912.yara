
rule m2318_61bd684dd8bf4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.61bd684dd8bf4912"
     cluster="m2318.61bd684dd8bf4912"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['03465e24e4b8e3f71915cd900497e4e0','0a0d0a98b1f914307d8c136934f3111b','adca898ced7fa129c27e2a321d277653']"

   strings:
      $hex_string = { 35393033423438373136433034393833363241383245434437454631343246444334414245334346353138454538333937353242453035324642343141363144 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
