
rule n26bf_081e98b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.081e98b9c8800b32"
     cluster="n26bf.081e98b9c8800b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="msilperseus malicious filerepmalware"
     md5_hashes="['cbc8def12428f2b48815b2e283e927a3b31eecca','18ae3104131e1437c76cabf76b280c49953ca56f','0c03b1d4ff0dab8dc0e4d2955a089bc94f2c0720']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.081e98b9c8800b32"

   strings:
      $hex_string = { 421fe1d52315cd1965612bb00c9ae77fbf691b07a18e4587e10556f74a5cfd2ce62e20557cdd9691a04b16600493cafcc000c7c1db49d4923536f0588da9acc4 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
