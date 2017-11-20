
rule m3e9_16c339171952f914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16c339171952f914"
     cluster="m3e9.16c339171952f914"
     cluster_size="551"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup kazy zbot"
     md5_hashes="['0076f4b8d213fdc30304aac35b4a10f8','01752a88029acd7c773f8864782ac7c7','10d84b4881300d435359aa2d7fb5d12c']"

   strings:
      $hex_string = { 7da3b8ea7ca2b703e6203a80e2243e84dee83188baec358cd6f02990d2f42d94cef82198aafc259cc6001aa0c2041ea4bec811a85acc15acf6cf09b0f2d30db4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
