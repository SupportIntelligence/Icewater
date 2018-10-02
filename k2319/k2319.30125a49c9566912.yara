
rule k2319_30125a49c9566912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.30125a49c9566912"
     cluster="k2319.30125a49c9566912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['bb86b03bfdaeefe5c94d42dc96637df950f0ff60','18acbec0491b3d3b01106533b115002b90d2044f','26526c4b5b360199730ebf33557ea5f759177de3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.30125a49c9566912"

   strings:
      $hex_string = { 27563859273a2866756e6374696f6e28297b76617220543d66756e6374696f6e28512c4b297b76617220753d4b262830783145443e2839342e2c30784142293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
