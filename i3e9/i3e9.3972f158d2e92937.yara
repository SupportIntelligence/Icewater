
rule i3e9_3972f158d2e92937
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.3972f158d2e92937"
     cluster="i3e9.3972f158d2e92937"
     cluster_size="620"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector aiucsjji malicious"
     md5_hashes="['00d9491994bb10151f3ffeaaf00b0d9d','02789140574b707530125e8d0a4e8fe0','0bd0d997616d2505b1764a0f4ecec7b6']"

   strings:
      $hex_string = { 0067024d756c746942797465546f576964654368617200ae036c737472636d7069410094025175657279506572666f726d616e6365436f756e74657200d40147 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
