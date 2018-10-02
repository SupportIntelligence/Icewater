
rule o3f8_492eada1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f8.492eada1c2000932"
     cluster="o3f8.492eada1c2000932"
     cluster_size="2550"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp androidos scamapp"
     md5_hashes="['280182ff544250c4fa24d3e298dafa2057a50bd8','96da211799004cdce4e7e437d872d7f64c2824e3','a731c9e334b2ab8eb8215818b442398f33c7b67e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o3f8.492eada1c2000932"

   strings:
      $hex_string = { 01b3061124000068016702203100006801d2049d3700006801a606263800006901f400712100006901e1047321000069019d05752c000069016409993500006a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
