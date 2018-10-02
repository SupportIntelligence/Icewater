
rule k2319_1952c2b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1952c2b9ca200b12"
     cluster="k2319.1952c2b9ca200b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6f29d0f5b008acf0808afc0aaa6409400b9b41a8','e7c81c63461796f1727ad1f8e12137796f8458e3','2ef83c7054dd200b9ff85da583171aef21c0ebc1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1952c2b9ca200b12"

   strings:
      $hex_string = { 646566696e6564297b72657475726e20545b6c5d3b7d76617220463d28362e303345323c3d2830783143362c3532293f2839302c313333293a28307832342c38 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
