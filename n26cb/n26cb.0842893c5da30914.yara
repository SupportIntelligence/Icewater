
rule n26cb_0842893c5da30914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26cb.0842893c5da30914"
     cluster="n26cb.0842893c5da30914"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy browsefox malicious"
     md5_hashes="['0dc7f26561943fac33d2f3d737600c66317e6dd5','620d44184d35e55848abe2d3c330bb0c682cabeb','9f97c1f8989a3f3121450ee56b59f7decd9f8e52']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26cb.0842893c5da30914"

   strings:
      $hex_string = { 3366613763626465666338316631613464353133666132633963340053657457696e496e657450726f787900546f537472696e67006765745f416c6c6f774469 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
