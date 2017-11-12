import "hash"

rule o3e9_52993834dbab1b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.52993834dbab1b32"
     cluster="o3e9.52993834dbab1b32"
     cluster_size="46 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy linkury bdff"
     md5_hashes="['c1401d8c5e4ac314b5b165f60c96446b', 'da4fe39308719a5fa8c3bc695e9bf709', '8db20030aefb4277c2c017cf2c42e029']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2721120,1044) == "7ed2738526c85bdece26d69829235672"
}

