import "hash"

rule o3e9_43b0ccc3c4001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0ccc3c4001912"
     cluster="o3e9.43b0ccc3c4001912"
     cluster_size="3153 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="parite small madang"
     md5_hashes="['8a80c07982720c0c4a9afa32857a613e', '0deaac5fe017fbce771e899d48bbac94', '416d6738d4a66b17bc51c266a237e784']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(823296,1024) == "87eb1721305da946a1b87ff9207f629a"
}

