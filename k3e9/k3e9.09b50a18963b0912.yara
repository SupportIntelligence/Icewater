
rule k3e9_09b50a18963b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.09b50a18963b0912"
     cluster="k3e9.09b50a18963b0912"
     cluster_size="226064"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malicious trojandropper"
     md5_hashes="['000036cb4c634c2ae24f30758ec0468f','00011410620e28a2181d92be1a3e9668','000a6b46cc667d7d099133f5829acb28']"

   strings:
      $hex_string = { cee71cae6ee0bf8af5fb867ffa4628bdeaf83c7131a2c37cbce492f1c65217b533aac553e94265136fcac89ea0320f380c5e9ced2187aa55c2b0735b0881c18d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
