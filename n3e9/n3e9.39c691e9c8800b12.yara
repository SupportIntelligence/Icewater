import "hash"

rule n3e9_39c691e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c691e9c8800b12"
     cluster="n3e9.39c691e9c8800b12"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy trojandropper backdoor"
     md5_hashes="['cbfd63635f7e276df65a4253f84bae11', 'aa4b9ff3b3daf8bad5e6e3daa2d5dd7b', 'bb7bf1fd434af0146bb736b166bbb11e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(413696,1076) == "ab5c78a222b72df8502930b7c2966067"
}

