import "hash"

rule k3e9_51b93306dda30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93306dda30932"
     cluster="k3e9.51b93306dda30932"
     cluster_size="118 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b093ce938ad1d32658986db6246f153d', 'ce16a00f7b36e33d4254dc9e9db5e317', '5651d16921be41700360bc80437fe5e2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4864,256) == "a123699e38ecb694dc0255cec9d6cbbb"
}

