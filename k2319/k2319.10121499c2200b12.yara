
rule k2319_10121499c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.10121499c2200b12"
     cluster="k2319.10121499c2200b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e35b672a92d595b69d5702b180d05bf2e5ed0d92','7058cc93a75453ecd3714d23519184caf98d50bc','639b6db0f08487d2ed631f9e653f46474b412873']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.10121499c2200b12"

   strings:
      $hex_string = { 756e646566696e6564297b72657475726e20465b535d3b7d76617220473d282830783134342c3938293c3d3134392e3f2837302c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
