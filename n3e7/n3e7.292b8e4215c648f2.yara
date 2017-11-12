
rule n3e7_292b8e4215c648f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.292b8e4215c648f2"
     cluster="n3e7.292b8e4215c648f2"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="guagua porntool tool"
     md5_hashes="['3d565251ed851668ffdc248675015dd3','5172f877fbbe655e73fee90aefafe83c','cad118e3d8e104ea09b4100471a8dae2']"

   strings:
      $hex_string = { fa598071d6b36a3a338861d3cd8439c2b898c8dd9d9c803b6ebf13d65fb109dd0a9d972494dc328e57917d736ccb8f07036c20aecdb893761f5d9a9de9163d28 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
