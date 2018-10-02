
rule n26bf_213e2a58d2bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.213e2a58d2bb1912"
     cluster="n26bf.213e2a58d2bb1912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy agen malicious"
     md5_hashes="['e0c69fbfc6dce4b37142c57649f9e42491c5942b','8cacfff9f95fee18f188e8893333ffdf1e3e4921','2583df7b5daf1a335570f5a7745d00e7b83d961a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.213e2a58d2bb1912"

   strings:
      $hex_string = { ffa0a394ff9ea092ff96998bff8b8e81ff7d8074ff6f7266ff62645aff595552ff342727ff291c1fff251a23ff211728ff1d142eff180f35ff150e3cff130b42 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
