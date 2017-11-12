
rule m3ed_3b9ac936916f4932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac936916f4932"
     cluster="m3ed.3b9ac936916f4932"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['087538b088e0f22d77345bbed0524ae1','498263678e8cf45593ac35fc743674b2','ddfdc5d7516d03c0c0221f3b535cf6e8']"

   strings:
      $hex_string = { 44494e47585850414444494e4750414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e47585850414444494e47504144 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
