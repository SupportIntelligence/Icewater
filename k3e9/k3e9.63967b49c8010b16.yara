import "hash"

rule k3e9_63967b49c8010b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63967b49c8010b16"
     cluster="k3e9.63967b49c8010b16"
     cluster_size="2512 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="upatre ipatre androm"
     md5_hashes="['15794ec4b8b07fd2ad3d79f9bd67c173', '2e56b8eaae27403dbe92206940e951d8', '048d35285ee65bf85132a0312eda2006']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4608,1024) == "9d5ca988b8bac62c4c49fb1133d85347"
}

