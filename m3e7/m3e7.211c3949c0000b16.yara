import "hash"

rule m3e7_211c3949c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.211c3949c0000b16"
     cluster="m3e7.211c3949c0000b16"
     cluster_size="77 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['0478e5e3031cdf69ba209f82c6594bb9', 'a798eba0239297e3b6827cb1af1c49b8', 'a0fbb5eaf315512cd5ebe1aec05a32b3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62090,1058) == "2cc91028f6f559f9c633c41bba0674cd"
}

