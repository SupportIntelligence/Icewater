
rule k3e9_1395b6abce200916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395b6abce200916"
     cluster="k3e9.1395b6abce200916"
     cluster_size="1209"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ipamor backdoor pyzbaukwkdpb"
     md5_hashes="['00844356ea61f3a8959f7a19c15e1645','00848a66685dd8c2d5039e9a7fa8328f','0309bd9c9fb550508db0ff8bd8378f6b']"

   strings:
      $hex_string = { 626c652d6661756c742e0056494e465f484d5f444f55424c455f4641554c5400496e76616c6964206f70636f646520627974652873292e00564552525f444953 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
