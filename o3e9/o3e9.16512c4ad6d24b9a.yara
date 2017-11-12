
rule o3e9_16512c4ad6d24b9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.16512c4ad6d24b9a"
     cluster="o3e9.16512c4ad6d24b9a"
     cluster_size="579"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['000aeb0c4fd63ef33281d7c7429c49fc','008727b36a13b4138a874c4abd8ed05e','09a81965bd90de7936f2d2134bb47070']"

   strings:
      $hex_string = { 10ba4197f16e8233062db04345a50ff8b28ab96dcfbeb9a4d9070d96a3abd50fe7f8a4c68f07ce1d25bacc20ed042e252aaa9c8979691f8eb7bb1efe62c665b6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
