
rule n3e9_0b9f15a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b9f15a1c2000b12"
     cluster="n3e9.0b9f15a1c2000b12"
     cluster_size="46"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="startpage razy downware"
     md5_hashes="['0367c4aa304c4839f283c8cbf30745e4','0b744120cd983f5b56b45fd546a212bb','79750741ba62fda9f6c2cd56f98f6ca9']"

   strings:
      $hex_string = { 7dd4f0e67f62deffb560508f59e093b6c48946bd41b965d11883b251e737353abc459b6c912d00aa0dc8af2ba6100f58694b12a2f1c6eefca4618bbf1f1a01e2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
