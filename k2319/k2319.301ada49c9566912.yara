
rule k2319_301ada49c9566912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.301ada49c9566912"
     cluster="k2319.301ada49c9566912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['0ce6bf0cc650a8c08962c254ad64cbbbfc6e4913','43939b0d931e683a4ec4a7ccf522ac4966343c47','1e408e1a00d3ba508674c2e121284eb7084236c2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.301ada49c9566912"

   strings:
      $hex_string = { 27563859273a2866756e6374696f6e28297b76617220543d66756e6374696f6e28512c4b297b76617220753d4b262830783145443e2839342e2c30784142293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
