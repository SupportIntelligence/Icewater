import "hash"

rule n3e9_610cee7ce22ed132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.610cee7ce22ed132"
     cluster="n3e9.610cee7ce22ed132"
     cluster_size="8073 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['00d61ed47253cd8511a135aae4eeb6bc', '01a5e242f16bec55f33ec50b1cb5057a', '00243359473763fc23af4e4869bb3bb7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(294912,1024) == "e9980409bd58ef812d6b8d5d6eaa1014"
}

