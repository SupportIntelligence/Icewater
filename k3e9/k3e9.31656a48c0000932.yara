
rule k3e9_31656a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.31656a48c0000932"
     cluster="k3e9.31656a48c0000932"
     cluster_size="438"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd trojandownloader"
     md5_hashes="['00a1f15bdc5ceeb22811ea2d9c2f58fe','024eb98e564f4040c6349ee22c01bb98','105f8294aa50674c031c36f1c8dc2c29']"

   strings:
      $hex_string = { 43a74e25f8ab648e040c0103d8b42bfaadf4c00e0c017c357426191d8bb60a0c01cd4d4a3e5e2f3942000c01522a2840441e3763060c0115db83fce6b2d61407 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
