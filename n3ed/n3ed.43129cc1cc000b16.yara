import "hash"

rule n3ed_43129cc1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.43129cc1cc000b16"
     cluster="n3ed.43129cc1cc000b16"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b95c1db278c453b03d3e01941ea17ea5', '8965319849ddddd16d67d87e1c5f4af4', '1f383076615fdb0d6ad1f607090a31d1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

