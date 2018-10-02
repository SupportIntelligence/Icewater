
rule n26c1_099a17a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c1.099a17a9ca000b12"
     cluster="n26c1.099a17a9ca000b12"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linux dofloo backdoor"
     md5_hashes="['c08f8355a44567579842fcf0f7ea699a6900a593','4ca00978da7e3d749666b98aef376714e817fac9','ee150e8ee4ae725a159501dd106407726ee93dc2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c1.099a17a9ca000b12"

   strings:
      $hex_string = { 5fec9e1201c9e76e099c1904600e10dfb01c97570d56407a3e500fce9a93021d6fd9a1260aa7c01eff969df5c6845a8f66bf2a42e8808b378226670bd6cdfee3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
