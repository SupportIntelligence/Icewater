import "hash"

rule n3e9_610cee7ce22ed132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.610cee7ce22ed132"
     cluster="n3e9.610cee7ce22ed132"
     cluster_size="8966 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['02de3ebeaaaf2f5172259d2799ad6250', '09ef401022791bc34d9b941c5373c7e6', '09e0acd4feb27fa968b218623cec00fe']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(294912,1024) == "e9980409bd58ef812d6b8d5d6eaa1014"
}

