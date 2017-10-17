import "hash"

rule k3e9_533ba316969f1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.533ba316969f1916"
     cluster="k3e9.533ba316969f1916"
     cluster_size="20 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['89f02b488d19ac29a510271fe4d6c9d5', '098f40b77e4c4043ccab45a18fd816d8', '89f02b488d19ac29a510271fe4d6c9d5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12800,1280) == "9bec7913a2600fdf8cf39f32c8126b0b"
}

