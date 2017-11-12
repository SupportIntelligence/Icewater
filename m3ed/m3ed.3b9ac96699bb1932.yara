
rule m3ed_3b9ac96699bb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac96699bb1932"
     cluster="m3ed.3b9ac96699bb1932"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['24746c8606f5efcf73426a2ad7b94d93','2792070bd24167536825405744be5fb9','d933f762020f5e587d14d9ef8aba2b07']"

   strings:
      $hex_string = { 44494e47585850414444494e4750414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e47585850414444494e47504144 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
