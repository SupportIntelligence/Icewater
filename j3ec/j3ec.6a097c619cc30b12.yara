
rule j3ec_6a097c619cc30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.6a097c619cc30b12"
     cluster="j3ec.6a097c619cc30b12"
     cluster_size="5"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="valla xorala valhalla"
     md5_hashes="['a1b2ce7a708af8ce738361c61ebf2ff6','a871b23c15297da83e8be87f63c45cb7','c3d7ba14caa49bdadf9869ac9e864830']"

   strings:
      $hex_string = { 33d2f7763c0bd2740140f7663c8987ef06000083bed000000000741b56578b7e5403fe8bcf2bcb8d77d8fdf3a4fc5f5e8386d000000028c703584f5200c74304 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
