
rule k3e9_1d267ec9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1d267ec9cc000912"
     cluster="k3e9.1d267ec9cc000912"
     cluster_size="298238"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd malicious"
     md5_hashes="['000059b42a61ba3849c6529edead9988','0000a9542946c9d2d6a490659b226469','000b132c8db967a9687138f7099c2760']"

   strings:
      $hex_string = { b75bcf1c514356870f75ca79f68954a06a1f494bded1f7500c99ef953fd3225e9c0a28d67b34967d391a3b640803925db4e1eda16697fa7cc724b8ff25b113d8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
