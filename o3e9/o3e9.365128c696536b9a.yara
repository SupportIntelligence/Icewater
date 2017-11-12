
rule o3e9_365128c696536b9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.365128c696536b9a"
     cluster="o3e9.365128c696536b9a"
     cluster_size="579"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['006446673a5c89e1c6fcd52981c10a41','015d2e3b88050ab9070647ed2b9fa14b','08ee7f359c72fb651ec2c684006cb830']"

   strings:
      $hex_string = { d2bbfdc78cba001238d7b6a10d7eeaaa0f0f68b7437a830344f3b87118106cd27d69bd6f513ed92f08f7dc3117c486ef74bfbec083fa44aea022ce93afcf0d68 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
