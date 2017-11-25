
rule n3e9_399121abc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.399121abc6620b12"
     cluster="n3e9.399121abc6620b12"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur polyransom"
     md5_hashes="['1ba7a27b2c7b883aecdd3389c7fa2979','a045df75d8f2db666914f2ce17eb7b98','eba6180c25fa9c6ef1b095b00758cf3f']"

   strings:
      $hex_string = { 010001002020000002002000a8100000010050414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e4758585041444449 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
