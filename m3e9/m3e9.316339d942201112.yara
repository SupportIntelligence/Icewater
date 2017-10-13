import "hash"

rule m3e9_316339d942201112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316339d942201112"
     cluster="m3e9.316339d942201112"
     cluster_size="152 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="vjadtre nimnul wapomi"
     md5_hashes="['b0d9b454f9c78bbc95123bfc39243546', 'f129d6560b28195730b04fdfe0a0f2e5', '8312fe1b07dfa94595fea5199515eafe']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64512,1024) == "85f1932459668fd27cfde94d6b3d6030"
}

