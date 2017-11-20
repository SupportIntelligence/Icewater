
rule k3e9_092b311e6a231912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.092b311e6a231912"
     cluster="k3e9.092b311e6a231912"
     cluster_size="94"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jeefo hidrag adload"
     md5_hashes="['0692cb183a85a7b1c5409ec00a937566','0a6617823878a9bf0710106969957f8c','31dae04adc1fab39550b4a07dc9cdf03']"

   strings:
      $hex_string = { bf29c130c32bc50cc731c936cb31cd17cf3ed138d343d5d6d77cdbdadbdcdd0edf14e112e31de516e71ce92ceb1cedeeef3cf108f3f5f539f767f967fb6cfd5f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
