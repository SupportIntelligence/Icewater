
rule k2319_301a5a49c9566912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.301a5a49c9566912"
     cluster="k2319.301a5a49c9566912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['ee71be456858b71847ac9af682a8eb520b709e6e','cf686eecaf50549126080d0cfee91408048a4953','b5d5aa91fe0ae7a790a083964e6961c962520c89']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.301a5a49c9566912"

   strings:
      $hex_string = { 27563859273a2866756e6374696f6e28297b76617220543d66756e6374696f6e28512c4b297b76617220753d4b262830783145443e2839342e2c30784142293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
