
rule k2319_191616b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.191616b9c8800b32"
     cluster="k2319.191616b9c8800b32"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['f2685442bca12455205f0194942d97cf71644186','b52f437d8659912173c45742c003286005a56ef5','ae4b5b686db583349ea546b587cc47d847f41027']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.191616b9c8800b32"

   strings:
      $hex_string = { 66696e6564297b72657475726e20765b4b5d3b7d766172204e3d28283133372e2c33372e293c3d307843433f2836382e2c30786363396532643531293a283132 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
