
rule k3e9_3c163ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c163ec9c4000b14"
     cluster="k3e9.3c163ec9c4000b14"
     cluster_size="57"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy simbot backdoor"
     md5_hashes="['09bc2b09221adaa51aa09ab5fd8b839b','1e180de4943cc3dfb56b1686a27bb1e4','a8af95f04d2429e6d38282a699c5ec0a']"

   strings:
      $hex_string = { 5400720061006e0073006c006100740069006f006e00000000000904b00450414444494e47585850414444494e4750414444494e47585850414444494e475041 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
